rule TTP_XOR_QUAD_CurrentVersionRun_ddda {
  strings:
    $key_ddda = { 8e b5 [2] aa bb [2] 81 97 [2] af b5 [2] bb ae [2] b4 b4 [2] aa a9 [2] a8 a8 [2] b3 ae [2] af a9 [2] b3 86 }

  condition:
    any of them
}