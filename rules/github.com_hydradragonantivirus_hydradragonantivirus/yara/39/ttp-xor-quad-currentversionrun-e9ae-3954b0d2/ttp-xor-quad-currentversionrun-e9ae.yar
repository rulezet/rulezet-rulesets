rule TTP_XOR_QUAD_CurrentVersionRun_e9ae {
  strings:
    $key_e9ae = { ba c1 [2] 9e cf [2] b5 e3 [2] 9b c1 [2] 8f da [2] 80 c0 [2] 9e dd [2] 9c dc [2] 87 da [2] 9b dd [2] 87 f2 }

  condition:
    any of them
}