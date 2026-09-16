rule TTP_XOR_QUAD_CurrentVersionRun_ddfe {
  strings:
    $key_ddfe = { 8e 91 [2] aa 9f [2] 81 b3 [2] af 91 [2] bb 8a [2] b4 90 [2] aa 8d [2] a8 8c [2] b3 8a [2] af 8d [2] b3 a2 }

  condition:
    any of them
}