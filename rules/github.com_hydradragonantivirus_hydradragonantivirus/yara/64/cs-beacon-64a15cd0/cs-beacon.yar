rule CS_beacon {
  meta:
    author = "Etienne Maynier tek@randhome.io"

  strings:
    $s1  = "%02d/%02d/%02d %02d:%02d:%02d" ascii
    $s2  = "%s as %s\\%s: %d" ascii
    $s3  = "Started service %s on %s" ascii
    $s4  = "beacon.dll" ascii
    $s5  = "beacon.x64.dll" ascii
    $s6  = "ReflectiveLoader" ascii
    $s7  = { 2e 2f 2e 2f 2e 2c ?? ?? 2e 2c 2e 2f }
    $s8  = { 69 68 69 68 69 6b ?? ?? 69 6b 69 68 }
    $s9  = "%s (admin)" ascii
    $s10 = "Updater.dll" ascii
    $s11 = "LibTomMath" ascii
    $s12 = "Content-Type: application/octet-stream" ascii

  condition:
    6 of them and filesize < 300000
}