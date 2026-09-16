rule TTP_XOR_QUAD_CurrentVersionRun_cc3d {
  strings:
    $key_cc3d = { 9f 52 [2] bb 5c [2] 90 70 [2] be 52 [2] aa 49 [2] a5 53 [2] bb 4e [2] b9 4f [2] a2 49 [2] be 4e [2] a2 61 }

  condition:
    any of them
}