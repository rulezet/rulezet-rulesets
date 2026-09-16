rule _20160921_02b826231ece268e91633311d2c70554_20160921_13a6ecf7a8d1_2604 {
  meta:
    description = "datamaliciousorder - from files 20160921_02b826231ece268e91633311d2c70554.js, 20160921_13a6ecf7a8d1b8c1e6c88d1f386d0fdc.js, 20160921_2746dcb029094ed409681059b0bf7b68.js, 20160921_331df381948e6d95c6a9496aeda63d16.js, 20160921_46b3ab412369507850a916abad1e6bf0.js, 20160921_4c22609fd7310d7f415ca007620a244b.js, 20160921_582a5b9e6263457a7095e1d0bf6ab96b.js, 20160921_63def3fff7f150b1f60fee716b458fd6.js, 20160921_c9a772728edf4eeff48c1aea32c00a13.js, 20160921_d6eab67b6b3cec2e5f5426840b084b70.js, 20160921_dff46b67b973e99ec02248f10c2f55c2.js, 20160921_ff1932b6e91481dd80ff6251296b57fe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4131eddf30a37bcc8a29ac1639ae3a6b259a3ecfc92b73a08091b2907434cf79"
    hash2       = "a1db38abaeb5bf0ea6f5b5ff0f4a9eedd9ce90cd62e2966ce8936e8e8fbc2905"
    hash3       = "9908788e148928c5f3ee88b22ad1ed33dbf69f1ffd103491ebd438b979bb77eb"
    hash4       = "74d3e5ca6efd3e26128cb4a5ab3009003c70f505b353304608d74dfd028df0d7"
    hash5       = "ff7968bb25038246a127bf97a5d4f0afb2c088f5ccd47c093b21d1aa27116fdd"
    hash6       = "2c98aee98a3263e75913535b49eb469916a931e86a23075b07289143bf0fa3f8"
    hash7       = "ef65e5e7f2b9ad6a0714382fda8dc9fde658333c4a3ea2cdf04558bfe763c3b6"
    hash8       = "85e2ab59983c4c704998f4c7c577cd8211e7b590b3f200f88616fe64954c10ea"
    hash9       = "76f52cefe2f1cf5954919532ecd1ec4c5c9072cb4edc435169d570baa9894ed9"
    hash10      = "0ae44892f78e5b5ddfc07e6a23fb55469f21e12c45e74661ad81e61b07893ece"
    hash11      = "2ea0ce06677c6aad57b6618a39beaa56b2c9060cb989c2213eb782aca5d747c2"
    hash12      = "07e5271d8517f89575dc2737fae5e8da89c7f2f25cd40c68e183d826da6b2bf0"

  strings:
    $s1 = "){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"ZIi\";}" ascii
    $s2 = "){return \"BMj\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";}" ascii
    $s3 = "on f000(){return \"Tb\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s4 = "ction f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"DYx\";})(),(function f000(){retur" ascii
    $s5 = "rn \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Mt\";})(),(fun" ascii
    $s6 = " \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Lo\";})(),(funct" ascii
    $s7 = "),(function f000(){return \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(function f000(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}