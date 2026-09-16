rule TTP_XOR_QUAD_CurrentVersionRun_572c {
  strings:
    $key_572c = { 04 43 [2] 20 4d [2] 0b 61 [2] 25 43 [2] 31 58 [2] 3e 42 [2] 20 5f [2] 22 5e [2] 39 58 [2] 25 5f [2] 39 70 }

  condition:
    any of them
}