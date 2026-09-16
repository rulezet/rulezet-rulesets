rule mpg4: MP4 {
  meta:
    author = "Joan Bono"

  strings:
    $a = { 00 00 00 14 66 74 79 70 69 73 6F 6D 00 00 00 01 }

  condition:
    $a at 0
}