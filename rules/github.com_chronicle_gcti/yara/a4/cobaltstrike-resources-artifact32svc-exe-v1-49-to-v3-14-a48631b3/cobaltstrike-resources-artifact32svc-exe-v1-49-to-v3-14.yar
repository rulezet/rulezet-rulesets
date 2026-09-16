rule CobaltStrike_Resources_Artifact32svc_Exe_v1_49_to_v3_14
{
	meta:
		description = "Cobalt Strike's resources/artifact32svc(big).exe and resources/artifact32uac(alt).exe signature for versions v1.49 to v3.14"
		hash =  "323ddf9623368b550def9e8980fde0557b6fe2dcd945fda97aa3b31c6c36d682"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	

	$decoderFunc = { 8B [2] 89 ?? 03 [2] 8B [2] 03 [5] 8B [2] 89 ?? C1 [2] C1 [2] 01 ?? 83 [2] 29 ?? 03 [5] 31 ?? 88 }
	
	condition:
		any of them
}