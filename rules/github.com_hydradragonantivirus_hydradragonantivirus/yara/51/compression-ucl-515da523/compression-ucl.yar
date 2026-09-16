rule compression_ucl {
  meta:
    author = "@tylabs"

  strings:
    $s1 = "UCL data compression library." wide
    $s2 = "Id: UCL version:" wide

  condition:
    all of them
}