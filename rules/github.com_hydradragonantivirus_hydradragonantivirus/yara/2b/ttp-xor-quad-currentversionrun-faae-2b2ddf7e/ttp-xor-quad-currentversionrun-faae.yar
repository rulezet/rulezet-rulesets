rule TTP_XOR_QUAD_CurrentVersionRun_faae {
  strings:
    $key_faae = { a9 c1 [2] 8d cf [2] a6 e3 [2] 88 c1 [2] 9c da [2] 93 c0 [2] 8d dd [2] 8f dc [2] 94 da [2] 88 dd [2] 94 f2 }

  condition:
    any of them
}