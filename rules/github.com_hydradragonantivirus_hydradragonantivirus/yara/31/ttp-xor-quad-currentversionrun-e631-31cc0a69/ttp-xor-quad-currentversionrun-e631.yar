rule TTP_XOR_QUAD_CurrentVersionRun_e631 {
  strings:
    $key_e631 = { b5 5e [2] 91 50 [2] ba 7c [2] 94 5e [2] 80 45 [2] 8f 5f [2] 91 42 [2] 93 43 [2] 88 45 [2] 94 42 [2] 88 6d }

  condition:
    any of them
}