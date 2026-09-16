rule TTP_XOR_QUAD_CurrentVersionRun_f73c {
  strings:
    $key_f73c = { a4 53 [2] 80 5d [2] ab 71 [2] 85 53 [2] 91 48 [2] 9e 52 [2] 80 4f [2] 82 4e [2] 99 48 [2] 85 4f [2] 99 60 }

  condition:
    any of them
}