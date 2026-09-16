rule TTP_XOR_QUAD_CurrentVersionRun_e120 {
  strings:
    $key_e120 = { b2 4f [2] 96 41 [2] bd 6d [2] 93 4f [2] 87 54 [2] 88 4e [2] 96 53 [2] 94 52 [2] 8f 54 [2] 93 53 [2] 8f 7c }

  condition:
    any of them
}