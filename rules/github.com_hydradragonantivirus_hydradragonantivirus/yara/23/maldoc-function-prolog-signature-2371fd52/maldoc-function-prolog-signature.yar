rule maldoc_function_prolog_signature : maldoc
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a1 = {55 8B EC 81 EC}
        $a2 = {55 8B EC 83 C4}
        $a3 = {55 8B EC E8}
        $a4 = {55 8B EC E9}
        $a5 = {55 8B EC EB}
    condition:
        any of them
}