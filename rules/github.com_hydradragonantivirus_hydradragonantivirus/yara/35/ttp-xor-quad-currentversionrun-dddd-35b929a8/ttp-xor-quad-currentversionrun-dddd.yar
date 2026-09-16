rule TTP_XOR_QUAD_CurrentVersionRun_dddd {
  strings:
    $key_dddd = { 8e b2 [2] aa bc [2] 81 90 [2] af b2 [2] bb a9 [2] b4 b3 [2] aa ae [2] a8 af [2] b3 a9 [2] af ae [2] b3 81 }

  condition:
    any of them
}