rule TTP_XOR_QUAD_CurrentVersionRun_e671 {
  strings:
    $key_e671 = { b5 1e [2] 91 10 [2] ba 3c [2] 94 1e [2] 80 05 [2] 8f 1f [2] 91 02 [2] 93 03 [2] 88 05 [2] 94 02 [2] 88 2d }

  condition:
    any of them
}