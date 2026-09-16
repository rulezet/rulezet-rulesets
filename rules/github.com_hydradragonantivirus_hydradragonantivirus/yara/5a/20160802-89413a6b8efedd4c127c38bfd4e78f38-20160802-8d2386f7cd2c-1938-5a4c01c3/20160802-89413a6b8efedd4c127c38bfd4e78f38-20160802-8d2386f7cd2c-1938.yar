rule _20160802_89413a6b8efedd4c127c38bfd4e78f38_20160802_8d2386f7cd2c_1938 {
  meta:
    description = "datamaliciousorder - from files 20160802_89413a6b8efedd4c127c38bfd4e78f38.js, 20160802_8d2386f7cd2c8ade2d65350b53722cbc.js, 20160802_ee2839601907846df1380b0738e515ce.js, 20160802_f18f22657a229916dbf0aec27c379bc4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "da1f3ce75fe404d2a90591c3272a2bbf79221e5b49790bbce6ef4f1c6b7572ae"
    hash2       = "cb981c4a5bbb74592ef414f6e026630632d93d57d553ec7e24f668c23417f0f8"
    hash3       = "adce6bae397465621c2dbf4b7310cf1281aaeb7aeeaa6aa3f9798687de59e9b0"
    hash4       = "b0bd1dc9f9cdf1c7a8e3a120e4cb816af6490698e85146aec53d52267c2eddc4"

  strings:
    $s1 = "x0avar Mz9=(BS\\x734 + If(Kg), Jl9 + CZy + IIk\\x32 + (function N\\x4by0(\\x29{return EYf;}()));\\r\\nvar Te\\x3dMz9[\\x51Sc + O" ascii
    $s2 = " Pe0=(D\\x763\\x20+ KJ\\x64 + (function IMn(){return CZ\\x698;}()), Zs5 + Te1 + S\\x75\\x28\\x4dSl) + Xt6);\\r\\nvar UWy4=Pe0[QS" ascii
    $s3 = "3\\x37\";\\r\\n\\x0d\\nvar E\\x52b=[SUf\\x32+Kx2 + (\\x66unction Fb(){retu\\x72n Ei;}())+Qc4+(function Zq9(){return Nl;}\\x28))" ascii
    $s4 = "\\r\\nvar NVd=(Mj + (\\x66unction\\x20O\\x695(){retur\\x6e EGw;}()) + Dh5\\x20+ Ca8 +\\x20(function E\\x50o(){r\\x65\\x74urn Wp;" ascii
    $s5 = " Pf0;};fu\\x6ection SGv(K\\x4cy5){return KLy5;};\\x66unc\\x74i\\x6fn\\x20\\x4aQu\\x28\\x4bKh4\\x29{retur\\x6e KKh4;};var OX\\x76" ascii

  condition:
    (uint16(0) == 0x200a and (all of them)
    ) or (all of them)
}