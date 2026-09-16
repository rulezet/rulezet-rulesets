rule TTP_XOR_QUAD_CurrentVersionRun_ccc0 {
  strings:
    $key_ccc0 = { 9f af [2] bb a1 [2] 90 8d [2] be af [2] aa b4 [2] a5 ae [2] bb b3 [2] b9 b2 [2] a2 b4 [2] be b3 [2] a2 9c }

  condition:
    any of them
}