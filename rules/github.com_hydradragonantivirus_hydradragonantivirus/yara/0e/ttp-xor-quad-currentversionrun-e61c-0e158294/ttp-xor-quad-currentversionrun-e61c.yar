rule TTP_XOR_QUAD_CurrentVersionRun_e61c {
  strings:
    $key_e61c = { b5 73 [2] 91 7d [2] ba 51 [2] 94 73 [2] 80 68 [2] 8f 72 [2] 91 6f [2] 93 6e [2] 88 68 [2] 94 6f [2] 88 40 }

  condition:
    any of them
}