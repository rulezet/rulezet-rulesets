rule TTP_XOR_QUAD_CurrentVersionRun_0722 {
  strings:
    $key_0722 = { 54 4d [2] 70 43 [2] 5b 6f [2] 75 4d [2] 61 56 [2] 6e 4c [2] 70 51 [2] 72 50 [2] 69 56 [2] 75 51 [2] 69 7e }

  condition:
    any of them
}