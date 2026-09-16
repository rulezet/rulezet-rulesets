rule TTP_XOR_QUAD_CurrentVersionRun_e641 {
  strings:
    $key_e641 = { b5 2e [2] 91 20 [2] ba 0c [2] 94 2e [2] 80 35 [2] 8f 2f [2] 91 32 [2] 93 33 [2] 88 35 [2] 94 32 [2] 88 1d }

  condition:
    any of them
}