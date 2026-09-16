rule TTP_XOR_QUAD_CurrentVersionRun_11f0 {
  strings:
    $key_11f0 = { 42 9f [2] 66 91 [2] 4d bd [2] 63 9f [2] 77 84 [2] 78 9e [2] 66 83 [2] 64 82 [2] 7f 84 [2] 63 83 [2] 7f ac }

  condition:
    any of them
}