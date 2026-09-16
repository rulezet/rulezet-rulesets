rule TTP_XOR_QUAD_CurrentVersionRun_f190 {
  strings:
    $key_f190 = { a2 ff [2] 86 f1 [2] ad dd [2] 83 ff [2] 97 e4 [2] 98 fe [2] 86 e3 [2] 84 e2 [2] 9f e4 [2] 83 e3 [2] 9f cc }

  condition:
    any of them
}