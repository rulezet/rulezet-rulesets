rule TTP_XOR_QUAD_CurrentVersionRun_ddc0 {
  strings:
    $key_ddc0 = { 8e af [2] aa a1 [2] 81 8d [2] af af [2] bb b4 [2] b4 ae [2] aa b3 [2] a8 b2 [2] b3 b4 [2] af b3 [2] b3 9c }

  condition:
    any of them
}