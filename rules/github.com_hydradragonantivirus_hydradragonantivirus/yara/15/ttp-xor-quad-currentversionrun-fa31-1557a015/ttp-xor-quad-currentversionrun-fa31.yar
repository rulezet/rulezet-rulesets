rule TTP_XOR_QUAD_CurrentVersionRun_fa31 {
  strings:
    $key_fa31 = { a9 5e [2] 8d 50 [2] a6 7c [2] 88 5e [2] 9c 45 [2] 93 5f [2] 8d 42 [2] 8f 43 [2] 94 45 [2] 88 42 [2] 94 6d }

  condition:
    any of them
}