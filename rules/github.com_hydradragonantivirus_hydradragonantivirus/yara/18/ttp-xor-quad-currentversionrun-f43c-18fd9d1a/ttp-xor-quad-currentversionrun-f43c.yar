rule TTP_XOR_QUAD_CurrentVersionRun_f43c {
  strings:
    $key_f43c = { a7 53 [2] 83 5d [2] a8 71 [2] 86 53 [2] 92 48 [2] 9d 52 [2] 83 4f [2] 81 4e [2] 9a 48 [2] 86 4f [2] 9a 60 }

  condition:
    any of them
}