rule TTP_XOR_QUAD_CurrentVersionRun_1911 {
  strings:
    $key_1911 = { 4a 7e [2] 6e 70 [2] 45 5c [2] 6b 7e [2] 7f 65 [2] 70 7f [2] 6e 62 [2] 6c 63 [2] 77 65 [2] 6b 62 [2] 77 4d }

  condition:
    any of them
}