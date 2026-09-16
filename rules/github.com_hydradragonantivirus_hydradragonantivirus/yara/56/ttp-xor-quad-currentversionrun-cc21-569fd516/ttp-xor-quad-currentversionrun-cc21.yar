rule TTP_XOR_QUAD_CurrentVersionRun_cc21 {
  strings:
    $key_cc21 = { 9f 4e [2] bb 40 [2] 90 6c [2] be 4e [2] aa 55 [2] a5 4f [2] bb 52 [2] b9 53 [2] a2 55 [2] be 52 [2] a2 7d }

  condition:
    any of them
}