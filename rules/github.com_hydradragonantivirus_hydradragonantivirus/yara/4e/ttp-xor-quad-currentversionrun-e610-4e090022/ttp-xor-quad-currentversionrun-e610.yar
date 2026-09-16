rule TTP_XOR_QUAD_CurrentVersionRun_e610 {
  strings:
    $key_e610 = { b5 7f [2] 91 71 [2] ba 5d [2] 94 7f [2] 80 64 [2] 8f 7e [2] 91 63 [2] 93 62 [2] 88 64 [2] 94 63 [2] 88 4c }

  condition:
    any of them
}