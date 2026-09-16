rule nullsoft_streaming_video: NSV {
  meta:
    author = "Joan Bono"

  strings:
    $a = "NSV"

  condition:
    $a at 0
}