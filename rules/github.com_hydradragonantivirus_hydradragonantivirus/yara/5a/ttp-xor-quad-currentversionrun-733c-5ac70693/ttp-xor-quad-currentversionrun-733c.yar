rule TTP_XOR_QUAD_CurrentVersionRun_733c {
  strings:
    $key_733c = { 20 53 [2] 04 5d [2] 2f 71 [2] 01 53 [2] 15 48 [2] 1a 52 [2] 04 4f [2] 06 4e [2] 1d 48 [2] 01 4f [2] 1d 60 }

  condition:
    any of them
}