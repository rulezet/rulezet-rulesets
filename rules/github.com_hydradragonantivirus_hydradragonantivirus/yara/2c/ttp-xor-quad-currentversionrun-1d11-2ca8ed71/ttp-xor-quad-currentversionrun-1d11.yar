rule TTP_XOR_QUAD_CurrentVersionRun_1d11 {
  strings:
    $key_1d11 = { 4e 7e [2] 6a 70 [2] 41 5c [2] 6f 7e [2] 7b 65 [2] 74 7f [2] 6a 62 [2] 68 63 [2] 73 65 [2] 6f 62 [2] 73 4d }

  condition:
    any of them
}