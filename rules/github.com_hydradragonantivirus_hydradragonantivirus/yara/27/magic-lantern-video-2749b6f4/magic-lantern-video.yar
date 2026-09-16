rule magic_lantern_video: MLV {
  meta:
    author = "Joan Bono"

  strings:
    $a = "MLVI"

  condition:
    $a at 0
}