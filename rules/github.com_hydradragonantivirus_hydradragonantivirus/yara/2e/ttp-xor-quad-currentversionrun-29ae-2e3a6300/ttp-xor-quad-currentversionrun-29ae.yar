rule TTP_XOR_QUAD_CurrentVersionRun_29ae {
  strings:
    $key_29ae = { 7a c1 [2] 5e cf [2] 75 e3 [2] 5b c1 [2] 4f da [2] 40 c0 [2] 5e dd [2] 5c dc [2] 47 da [2] 5b dd [2] 47 f2 }

  condition:
    any of them
}