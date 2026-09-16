rule TTP_XOR_QUAD_CurrentVersionRun_f1f0 {
  strings:
    $key_f1f0 = { a2 9f [2] 86 91 [2] ad bd [2] 83 9f [2] 97 84 [2] 98 9e [2] 86 83 [2] 84 82 [2] 9f 84 [2] 83 83 [2] 9f ac }

  condition:
    any of them
}