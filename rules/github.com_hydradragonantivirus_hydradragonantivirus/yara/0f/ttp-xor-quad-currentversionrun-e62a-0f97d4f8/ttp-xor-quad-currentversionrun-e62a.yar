rule TTP_XOR_QUAD_CurrentVersionRun_e62a {
  strings:
    $key_e62a = { b5 45 [2] 91 4b [2] ba 67 [2] 94 45 [2] 80 5e [2] 8f 44 [2] 91 59 [2] 93 58 [2] 88 5e [2] 94 59 [2] 88 76 }

  condition:
    any of them
}