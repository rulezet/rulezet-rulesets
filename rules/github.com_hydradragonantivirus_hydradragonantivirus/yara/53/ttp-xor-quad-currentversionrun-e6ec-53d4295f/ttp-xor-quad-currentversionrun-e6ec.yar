rule TTP_XOR_QUAD_CurrentVersionRun_e6ec {
  strings:
    $key_e6ec = { b5 83 [2] 91 8d [2] ba a1 [2] 94 83 [2] 80 98 [2] 8f 82 [2] 91 9f [2] 93 9e [2] 88 98 [2] 94 9f [2] 88 b0 }

  condition:
    any of them
}