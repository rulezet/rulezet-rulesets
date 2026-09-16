rule TTP_XOR_QUAD_CurrentVersionRun_2f3c {
  strings:
    $key_2f3c = { 7c 53 [2] 58 5d [2] 73 71 [2] 5d 53 [2] 49 48 [2] 46 52 [2] 58 4f [2] 5a 4e [2] 41 48 [2] 5d 4f [2] 41 60 }

  condition:
    any of them
}