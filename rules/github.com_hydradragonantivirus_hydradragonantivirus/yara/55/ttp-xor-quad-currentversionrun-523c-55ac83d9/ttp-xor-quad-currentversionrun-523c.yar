rule TTP_XOR_QUAD_CurrentVersionRun_523c {
  strings:
    $key_523c = { 01 53 [2] 25 5d [2] 0e 71 [2] 20 53 [2] 34 48 [2] 3b 52 [2] 25 4f [2] 27 4e [2] 3c 48 [2] 20 4f [2] 3c 60 }

  condition:
    any of them
}