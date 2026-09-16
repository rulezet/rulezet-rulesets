rule TTP_XOR_QUAD_CurrentVersionRun_e601 {
  strings:
    $key_e601 = { b5 6e [2] 91 60 [2] ba 4c [2] 94 6e [2] 80 75 [2] 8f 6f [2] 91 72 [2] 93 73 [2] 88 75 [2] 94 72 [2] 88 5d }

  condition:
    any of them
}