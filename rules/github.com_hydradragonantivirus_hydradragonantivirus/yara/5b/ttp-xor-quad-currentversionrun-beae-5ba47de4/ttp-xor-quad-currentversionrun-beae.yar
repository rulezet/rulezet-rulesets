rule TTP_XOR_QUAD_CurrentVersionRun_beae {
  strings:
    $key_beae = { ed c1 [2] c9 cf [2] e2 e3 [2] cc c1 [2] d8 da [2] d7 c0 [2] c9 dd [2] cb dc [2] d0 da [2] cc dd [2] d0 f2 }

  condition:
    any of them
}