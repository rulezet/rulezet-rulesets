rule TTP_XOR_QUAD_CurrentVersionRun_edfc {
  strings:
    $key_edfc = { be 93 [2] 9a 9d [2] b1 b1 [2] 9f 93 [2] 8b 88 [2] 84 92 [2] 9a 8f [2] 98 8e [2] 83 88 [2] 9f 8f [2] 83 a0 }

  condition:
    any of them
}