rule CS_encrypted_beacon_x86_64 {
  meta:
    author = "Etienne Maynier tek@randhome.io"

  strings:
    $s1 = { fc 48 83 e4 f0 eb 33 5d 8b 45 00 48 83 c5 04 8b }

  condition:
    $s1 at 0 and filesize < 300000
}