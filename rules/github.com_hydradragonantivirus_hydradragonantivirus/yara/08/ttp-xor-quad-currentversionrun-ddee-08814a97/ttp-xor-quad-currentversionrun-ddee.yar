rule TTP_XOR_QUAD_CurrentVersionRun_ddee {
  strings:
    $key_ddee = { 8e 81 [2] aa 8f [2] 81 a3 [2] af 81 [2] bb 9a [2] b4 80 [2] aa 9d [2] a8 9c [2] b3 9a [2] af 9d [2] b3 b2 }

  condition:
    any of them
}