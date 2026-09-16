rule TTP_XOR_QUAD_CurrentVersionRun_0211 {
  strings:
    $key_0211 = { 51 7e [2] 75 70 [2] 5e 5c [2] 70 7e [2] 64 65 [2] 6b 7f [2] 75 62 [2] 77 63 [2] 6c 65 [2] 70 62 [2] 6c 4d }

  condition:
    any of them
}