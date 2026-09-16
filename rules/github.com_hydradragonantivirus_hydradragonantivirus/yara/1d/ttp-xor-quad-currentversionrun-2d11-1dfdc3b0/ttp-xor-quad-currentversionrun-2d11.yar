rule TTP_XOR_QUAD_CurrentVersionRun_2d11 {
  strings:
    $key_2d11 = { 7e 7e [2] 5a 70 [2] 71 5c [2] 5f 7e [2] 4b 65 [2] 44 7f [2] 5a 62 [2] 58 63 [2] 43 65 [2] 5f 62 [2] 43 4d }

  condition:
    any of them
}