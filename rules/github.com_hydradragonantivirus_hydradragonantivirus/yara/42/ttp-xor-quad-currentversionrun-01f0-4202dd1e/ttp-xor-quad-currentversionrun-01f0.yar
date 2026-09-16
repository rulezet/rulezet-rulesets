rule TTP_XOR_QUAD_CurrentVersionRun_01f0 {
  strings:
    $key_01f0 = { 52 9f [2] 76 91 [2] 5d bd [2] 73 9f [2] 67 84 [2] 68 9e [2] 76 83 [2] 74 82 [2] 6f 84 [2] 73 83 [2] 6f ac }

  condition:
    any of them
}