rule TTP_XOR_QUAD_CurrentVersionRun_5722 {
  strings:
    $key_5722 = { 04 4d [2] 20 43 [2] 0b 6f [2] 25 4d [2] 31 56 [2] 3e 4c [2] 20 51 [2] 22 50 [2] 39 56 [2] 25 51 [2] 39 7e }

  condition:
    any of them
}