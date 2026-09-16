rule XProtect_MACOS_11eaac1 {
  meta:
    description = "MACOS.11eaac1"

  strings:
    $a1 = "#!"

    $b1 = "tail +"
    $b2 = "funzip -"
    $b3 = "mktemp -d -t x"
    $b4 = { 63 68 6d 6f 64 20 2d 52 [0-1] 20 37 35 35 }
    $b5 = { 6b 69 6c 6c 61 6c 6c 20 [0-3] 54 65 72 6d 69 6e 61 6c }
    $b6 = "nohup $TMPDIR/*.app/Contents/MacOS/"

    $c1 = { 50 4b 03 04 0a }

  condition:
    filesize < 500KB and $a1 at 0 and 4 of ($b*) and $c1
}