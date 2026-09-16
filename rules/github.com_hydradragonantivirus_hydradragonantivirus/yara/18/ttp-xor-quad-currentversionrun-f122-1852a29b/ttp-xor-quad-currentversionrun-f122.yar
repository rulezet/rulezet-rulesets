rule TTP_XOR_QUAD_CurrentVersionRun_f122 {
  strings:
    $key_f122 = { a2 4d [2] 86 43 [2] ad 6f [2] 83 4d [2] 97 56 [2] 98 4c [2] 86 51 [2] 84 50 [2] 9f 56 [2] 83 51 [2] 9f 7e }

  condition:
    any of them
}