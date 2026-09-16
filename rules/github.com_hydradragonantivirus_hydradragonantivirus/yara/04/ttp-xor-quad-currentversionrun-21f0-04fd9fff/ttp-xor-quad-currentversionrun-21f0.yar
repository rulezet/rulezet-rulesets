rule TTP_XOR_QUAD_CurrentVersionRun_21f0 {
  strings:
    $key_21f0 = { 72 9f [2] 56 91 [2] 7d bd [2] 53 9f [2] 47 84 [2] 48 9e [2] 56 83 [2] 54 82 [2] 4f 84 [2] 53 83 [2] 4f ac }

  condition:
    any of them
}