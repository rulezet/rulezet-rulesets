rule _20160921_23ef471e720525eb3dff80c2296d1a60_20160921_32423c6c4f53_4729 {
  meta:
    description = "datamaliciousorder - from files 20160921_23ef471e720525eb3dff80c2296d1a60.js, 20160921_32423c6c4f53c5e0240449620e4b98c9.js, 20160921_382a0f9b1ae693f8ade627fd2d6a8b52.js, 20160921_3974cbb8b2af1f98b68ab31621da93d9.js, 20160921_4b85b9629682d9cbd379b3404bd09eb1.js, 20160921_54325d6949c5c03d42a42e11b24dee5c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b0945c221a3a5ff2958847eac00c479ff3a9b1c8dd949684148aca0eeaf3afeb"
    hash2       = "1627aa0e729ffe8aba0e7faa8a6286c25a744600e193b72dbc3254fcc98a6003"
    hash3       = "4170edc38601b30ac37c9e43a569e4e01000505e73d89702266efb685dc6a8ac"
    hash4       = "707fba854060aa6294a0cf0c11b8eed992c56785375920bc41b7e95f514ab760"
    hash5       = "43de7c579d15cb70a31da759a94145ff9a831b9bf0e5ff93ae38b5064231b62f"
    hash6       = "0fa3791b48292bf705ed06d701118840e9c87ae1f9ac323fe09b8ad04cedc171"

  strings:
    $s1 = ";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Nv\";})(),(function f0" ascii
    $s2 = "(){return \"Iq\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Sv\";})" ascii
    $s3 = "tion f000(){return \"NBs\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Qa\";})(),(function f000(){return" ascii
    $s4 = "\"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Go\";})(),(funct" ascii
    $s5 = "on f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"KDh\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}