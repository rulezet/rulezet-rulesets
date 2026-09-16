import "pe"
rule Soraco_License_Manager : Soraco Technologies Inc
{
	meta:
		author="_pusher_"
		date = "2016-09"
		description = "www.soraco.co"
	condition:
		(
		pe.exports("QlmGetStatus") and pe.exports("QlmGetVersion") and pe.exports("QlmGetProductID") 
		and ( pe.exports("QlmIsEvaluation") or pe.exports("QlmIsValid") )
		)
}